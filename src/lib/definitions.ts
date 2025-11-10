import * as z from 'zod';

export const createAdminSchema = z.object({
    name: z.string()
        .min(1, 'Nome é obrigatório'),
    email: z.email('Endereço de e-mail inválido')
        .trim()
        .toLowerCase(),
    password: z.string()
        .min(8, 'A senha deve ter pelo menos 8 caracteres'),
    password_confirmation: z.string()
        .min(1, 'Por favor confirme sua senha')
})
    .refine((data) => data.password === data.password_confirmation, {
        message: 'As senhas não correspondem',
        path: ['password_confirmation']
    });

export function getSignUpUpdateSchema(formData: FormData) {
    const isEdit = Boolean(formData.get('id'));

    return z.object({
        name: z.string()
            .min(1, 'Nome é obrigatório'),
        email: z.email('Endereço de e-mail inválido')
            .trim()
            .toLowerCase(),
        password: isEdit
            ? z.string().optional()
            : z.string().min(8, 'A senha deve ter pelo menos 8 caracteres'),
        password_confirmation: isEdit
            ? z.string().optional()
            : z.string().min(1, 'Por favor confirme sua senha'),
        role: z.enum(['ADMIN', 'USER'], {
            error: 'A função deve ser USUÁRIA(O) ou ADMINISTRADOR(A)'
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

export const signInSchema = z.object({
    email: z.email('E-mail inválido')
        .trim()
        .toLowerCase(),
    password: z.string()
        .min(8, 'A senha deve ter mais de 8 caracteres')
        .max(32, 'A senha deve ter menos de 32 caracteres')
})

export const updateUserSchema = z.object({
    name: z.string()
        .min(1, 'Nome é obrigatório'),
    email: z.email('E-mail inválido')
        .trim()
        .toLowerCase()
})

export const deleteUserSchema = z.object({
    password: z.string()
        .min(8, 'A senha deve ter pelo menos 8 caracteres')
})

export const passwordUpdateSchema = z.object({
    current_password: z.string()
        .min(8, 'A senha deve ter pelo menos 8 caracteres'),
    password: z.string()
        .min(8, 'A senha deve ter pelo menos 8 caracteres'),
    password_confirmation: z.string()
        .min(8, 'Por favor confirme sua senha')
})
    .refine((data) => data.password === data.password_confirmation, {
        message: 'As senhas não correspondem',
        path: ['password_confirmation']
    });

export const passwordResetSchema = z.object({
    email: z.email('E-mail inválido')
        .trim()
        .toLowerCase(),
    token: z.string()
        .min(1, 'Token é necessário'),
    password: z.string()
        .min(8, 'A senha deve ter mais de 8 caracteres'),
    password_confirmation: z.string()
        .min(1, 'Por favor confirme sua senha')
})
    .refine((data) => data.password === data.password_confirmation, {
        message: 'As senhas não correspondem',
        path: ['password_confirmation']
    });

export const passwordForgotSchema = z.object({
    email: z.email('E-mail inválido')
        .trim()
        .toLowerCase()
});

export type FormStateCreateAdmin =
    | {
        errors?: {
            name?: string[];
            email?: string[];
            password?: string[];
            password_confirmation?: string[];
            image?: string[];
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
            image?: string[];
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
            image?: string[];
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