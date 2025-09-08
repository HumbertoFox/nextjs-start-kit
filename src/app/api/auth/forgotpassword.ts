'use server';

import { sendPasswordResetEmail } from '@/lib/mail';
import { FormStatePasswordForgot, passwordForgotSchema } from '@/lib/definitions';
import crypto from 'crypto';
import prisma from '@/lib/prisma';

export async function forgotPassword(state: FormStatePasswordForgot, formData: FormData): Promise<FormStatePasswordForgot> {
    const validatedFields = passwordForgotSchema.safeParse({ email: formData.get('email') as string });

    if (!validatedFields.success) return { errors: validatedFields.error.flatten().fieldErrors };

    const { email } = validatedFields.data;

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) return { message: 'Se seu e-mail estiver registrado, você receberá um link para redefinir sua senha.' };

    const tokenExisting = await prisma.verificationToken.findFirst({ where: { identifier: email } });

    if (!tokenExisting || new Date() > tokenExisting.expires) {
        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 60 * 60 * 1000);

        await prisma.verificationToken.create({ data: { identifier: email, token, expires } });

        const resetLink = `${process.env.NEXT_URL}/auth/reset-password?token=${token}&email=${email}`;

        await sendPasswordResetEmail(email, resetLink);

        return { message: 'Se seu e-mail estiver registrado, você receberá um link para redefinir sua senha.' };
    }

    return { message: 'Se seu e-mail estiver registrado, você receberá um link para redefinir sua senha.' };
}