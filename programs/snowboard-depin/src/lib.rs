use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use solana_program::sysvar::instructions as sysvar_instructions;
use solana_program::ed25519_program;

declare_id!("EniMLABsumavDA61s9y5i4NHi9vGW8749dpedqa5az8m"); // Твой Program ID

#[program]
pub mod miii_protocol {
    use super::*;

    // 1. Регистрация устройства (Датчик)
    pub fn register_device(
        ctx: Context<RegisterDevice>,
        device_pubkey: Pubkey,
    ) -> Result<()> {
        let registry = &mut ctx.accounts.device_registry;
        registry.owner = ctx.accounts.owner.key();
        registry.device_pubkey = device_pubkey;
        registry.is_active = true;
        registry.sequence = 0;
        registry.bump = ctx.bumps.device_registry;
        emit!(DeviceRegistered { device: device_pubkey, owner: registry.owner });
        Ok(())
    }

    // 2. Запись трюка с верификацией Ed25519 (Главная фича!)
    pub fn record_motion(
        ctx: Context<RecordMotion>,
        trick_type: u8,
        g_force: u32,
        timestamp: i64,
        sequence: u64,
    ) -> Result<()> {
        let registry = &mut ctx.accounts.device_registry;
        let event = &mut ctx.accounts.motion_event;
        
        require!(registry.is_active, CustomError::DeviceInactive);
        require!(registry.owner == ctx.accounts.user.key(), CustomError::UnauthorizedUser);

        // --- ПРОВЕРКА ED25519 ПОДПИСИ ---
        // Используем Vec вместо format! (чтобы не было ошибки с heap-памятью)
        let mut message = Vec::new();
        message.extend_from_slice(&trick_type.to_le_bytes());
        message.extend_from_slice(&g_force.to_le_bytes());
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(&sequence.to_le_bytes());

        verify_ed25519_signature(
            &ctx.accounts.instructions_sysvar,
            &registry.device_pubkey,
            &message,
        )?;

        require!(sequence == registry.sequence, CustomError::InvalidSequence);
        require!(g_force <= 1500, CustomError::PhysicsLimitExceeded); // Max 15G

        event.device = registry.device_pubkey;
        event.user = ctx.accounts.user.key();
        event.trick_type = trick_type;
        event.g_force = g_force;
        event.timestamp = timestamp;
        event.sequence = sequence;

        registry.sequence = registry.sequence.checked_add(1).ok_or(CustomError::Overflow)?;
        emit!(MotionRecorded { device: event.device, user: event.user, trick_type, g_force, timestamp });
        Ok(())
    }

    // 3. Стейкинг (для доступа к B2B данным)
    pub fn stake_for_access(ctx: Context<StakeForAccess>, amount: u64) -> Result<()> {
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        emit!(Staked { user: ctx.accounts.user.key(), amount });
        Ok(())
    }
}

// --- ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ ED25519 ---
fn verify_ed25519_signature(
    instructions_sysvar: &UncheckedAccount,
    expected_pubkey: &Pubkey,
    expected_message: &[u8],
) -> Result<()> {
    let instructions = sysvar_instructions::load_instruction_at_checked(
        0, 
        &instructions_sysvar.to_account_info()
    ).map_err(|_| error!(CustomError::MissingEd25519Instruction))?;

    require!(instructions.program_id == ed25519_program::id(), CustomError::InvalidEd25519Instruction);

    let data = instructions.data;
    let num_signatures = data[0];
    require!(num_signatures == 1, CustomError::InvalidEd25519Instruction);

    // Парсинг полей Ed25519 инструкции (стандарт Solana)
    let public_key_offset = u16::from_le_bytes([data[6], data[7]]) as usize;
    let message_data_offset = u16::from_le_bytes([data[10], data[11]]) as usize;
    let message_data_size = u16::from_le_bytes([data[12], data[13]]) as usize;

    let pubkey_bytes: [u8; 32] = data[public_key_offset..public_key_offset + 32].try_into().unwrap();
    require!(&pubkey_bytes == expected_pubkey.as_ref(), CustomError::InvalidDeviceSignature);

    let message = &data[message_data_offset..message_data_offset + message_data_size];
    require!(message == expected_message, CustomError::InvalidSignedMessage);

    Ok(())
}

// --- АККАУНТЫ И СТРУКТУРЫ ---

#[derive(Accounts)]
#[instruction(device_pubkey: Pubkey)] // Добавлено для работы seeds
pub struct RegisterDevice<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        init, 
        payer = owner, 
        space = 8 + 32 + 32 + 1 + 8 + 8 + 1, 
        seeds = [b"device", device_pubkey.as_ref()], 
        bump
    )]
    pub device_registry: Account<'info, DeviceRegistry>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RecordMotion<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    /// CHECK: This is the Solana instructions sysvar, verified by address constraint.
    #[account(address = sysvar_instructions::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
    
    #[account(
        mut, 
        seeds = [b"device", device_registry.device_pubkey.as_ref()], 
        bump = device_registry.bump
    )]
    pub device_registry: Account<'info, DeviceRegistry>,
    
    #[account(
        init, 
        payer = user, 
        space = 8 + 32 + 32 + 1 + 4 + 8 + 8 + 1, 
        seeds = [b"motion", device_registry.device_pubkey.as_ref(), &device_registry.sequence.to_le_bytes()], 
        bump
    )]
    pub motion_event: Account<'info, MotionEvent>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StakeForAccess<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct DeviceRegistry {
    pub owner: Pubkey,
    pub device_pubkey: Pubkey,
    pub is_active: bool,
    pub sequence: u64,
    pub last_timestamp: i64,
    pub bump: u8,
}

#[account]
pub struct MotionEvent {
    pub device: Pubkey,
    pub user: Pubkey,
    pub trick_type: u8,
    pub g_force: u32,
    pub timestamp: i64,
    pub sequence: u64,
    pub bump: u8,
}

// --- СОБЫТИЯ И ОШИБКИ ---
#[event] pub struct DeviceRegistered { pub device: Pubkey, pub owner: Pubkey }
#[event] pub struct MotionRecorded { pub device: Pubkey, pub user: Pubkey, pub trick_type: u8, pub g_force: u32, pub timestamp: i64 }
#[event] pub struct Staked { pub user: Pubkey, pub amount: u64 }

#[error_code]
pub enum CustomError {
    #[msg("Device is inactive")] DeviceInactive,
    #[msg("Unauthorized user")] UnauthorizedUser,
    #[msg("Invalid sequence")] InvalidSequence,
    #[msg("Physics limit exceeded")] PhysicsLimitExceeded,
    #[msg("Overflow")] Overflow,
    #[msg("Missing Ed25519 instruction")] MissingEd25519Instruction,
    #[msg("Invalid Ed25519 instruction")] InvalidEd25519Instruction,
    #[msg("Invalid device signature")] InvalidDeviceSignature,
    #[msg("Invalid signed message")] InvalidSignedMessage,
}
