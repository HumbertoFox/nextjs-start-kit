'use server';

import { FormStatePasswordReset, passwordResetSchema } from '@/lib/definitions';
import prisma from '@/lib/prisma';
import { hash } from 'bcrypt-ts';

export async function resetPassword(state: FormStatePasswordReset, formData: FormData): Promise<FormStatePasswordReset> {
    const validatedFields = passwordResetSchema.safeParse({
        email: formData.get('email') as string,
        token: formData.get('token') as string,
        password: formData.get('password') as string,
        password_confirmation: formData.get('password_confirmation') as string
    });

    if (!validatedFields.success) return { errors: validatedFields.error.flatten().fieldErrors };

    const { email, token, password } = validatedFields.data;

    const tokenExisting = await prisma.verificationToken.findUnique({ where: { identifier_token: { identifier: email, token } } });

    if (!tokenExisting || tokenExisting.expires < new Date()) return { warning: 'Token inválido ou expirado.' };

    const hashedPassword = await hash(password, 12);

    await prisma.user.update({ where: { email }, data: { password: hashedPassword } });

    await prisma.verificationToken.delete({ where: { identifier_token: { identifier: email, token } } });

    return { message: 'Senha redefinida com sucesso!' };
}