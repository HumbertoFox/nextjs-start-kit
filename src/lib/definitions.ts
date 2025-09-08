import { z, object, string, email } from 'zod';

export const createAdminSchema = object({
    name: string()
        .min(1, 'Nome é obrigatório'),
    email: email('Endereço de e-mail inválido'),
    password: string()
        .min(8, 'A senha deve ter pelo menos 8 caracteres'),
    password_confirmation: string()
        .min(1, 'Por favor confirme sua senha')
})
    .refine((data) => data.password === data.password_confirmation, {
        message: 'As senhas não correspondem',
        path: ['password_confirmation']
    });

export function getSignUpUpdateSchema(formData: FormData) {
    const isEdit = Boolean(formData.get('id'));

    return object({
        name: string()
            .min(1, 'Nome é obrigatório'),
        email: email('Endereço de e-mail inválido'),
        password: isEdit
            ? string().optional()
            : string().min(8, 'A senha deve ter pelo menos 8 caracteres'),
        password_confirmation: isEdit
            ? string().optional()
            : string().min(1, 'Por favor confirme sua senha'),
        role: z.enum(['ADMIN', 'USER'], {
            error: 'A função deve ser USUÁRIO ou ADMINISTRADOR(A)'
        })
    })
        .superRefine((data, ctx) => {
            if (data.password && data.password !== data.password_confirmation) {
                ctx.addIssue({
                    path: ['password_confirmation'],
                    code: 'custom',
                    message: 'As senhas não correspondem',
                });
            }
        });
}

export const signInSchema = object({
    email: email('E-mail inválido'),
    password: string()
        .min(8, 'A senha deve ter mais de 8 caracteres')
        .max(32, 'A senha deve ter menos de 32 caracteres')
})

export const updateUserSchema = object({
    name: string()
        .min(1, 'Nome é obrigatório'),
    email: email('E-mail inválido')
})

export const deleteUserSchema = object({
    password: string()
        .min(8, 'A senha deve ter pelo menos 8 caracteres')
})

export const passwordUpdateSchema = object({
    current_password: string()
        .min(8, 'A senha deve ter pelo menos 8 caracteres'),
    password: string()
        .min(8, 'A senha deve ter pelo menos 8 caracteres'),
    password_confirmation: string()
        .min(8, 'Por favor confirme sua senha')
})
    .refine((data) => data.password === data.password_confirmation, {
        message: 'As senhas não correspondem',
        path: ['password_confirmation']
    });

export const passwordResetSchema = object({
    email: email('E-mail inválido'),
    token: string()
        .min(1, 'Token é necessário'),
    password: string()
        .min(8, 'A senha deve ter mais de 8 caracteres'),
    password_confirmation: string()
        .min(1, 'Por favor confirme sua senha')
})
    .refine((data) => data.password === data.password_confirmation, {
        message: 'As senhas não correspondem',
        path: ['password_confirmation']
    });

export const passwordForgotSchema = object({
    email: email('E-mail inválido')
});

export type FormStateCreateAdmin =
    | {
        errors?: {
            name?: string[];
            email?: string[];
            password?: string[];
            password_confirmation?: string[];
        }
        message?: boolean;
        warning?: string;
    } | undefined;

export type FormStateCreateUpdateAdminUser =
    | {
        errors?: {
            name?: string[];
            email?: string[];
            role?: string[];
            password?: string[];
            password_confirmation?: string[];
        }
        message?: boolean;
    } | undefined;

export type FormStateLoginUser =
    | {
        errors?: {
            email?: string[];
            password?: string[];
        }
        message?: string;
        warning?: string;
    } | undefined;

export type FormStateUserDelete =
    | {
        errors?: {
            password?: string[];
        }
        message?: boolean;
    } | undefined;

export type FormStatePasswordUpdate =
    | {
        errors?: {
            current_password?: string[];
            password?: string[];
            password_confirmation?: string[];
        }
        message?: boolean;
    } | undefined;

export type FormStateUserUpdate =
    | {
        errors?: {
            name?: string[];
            email?: string[];
        };
        message?: string;
        success?: boolean;
    } | undefined;

export type FormStatePasswordForgot =
    | {
        errors?: {
            email?: string[];
        }
        message?: string;
    } | undefined;

export type FormStatePasswordReset =
    | {
        errors?: {
            email?: string[];
            token?: string[];
            password?: string[];
            password_confirmation?: string[];
        }
        message?: string;
        warning?: string;
    } | undefined;