'use server';

import prisma from '@/lib/prisma';
import { FormStateLoginUser, signInSchema } from '@/lib/definitions';
import { compare } from 'bcrypt-ts';
import { createSession } from '@/lib/session';

export async function loginUser(state: FormStateLoginUser, formData: FormData): Promise<FormStateLoginUser> {
    const validatedFields = signInSchema.safeParse({
        email: formData.get('email') as string,
        password: formData.get('password') as string,
    });

    if (!validatedFields.success) return { errors: validatedFields.error.flatten().fieldErrors, };

    const { email, password } = validatedFields.data;

    try {
        const user = await prisma.user.findFirst({ where: { email, deletedAt: null } });

        if (!user) return { warning: 'E-mail ou senha inválidos' };

        const isPasswordValid = await compare(password, user.password);

        if (!isPasswordValid) return { warning: 'E-mail ou senha inválidos' };

        await createSession(user.id, user.role);

        return { message: 'Autenticação bem-sucedida! Redirecionando para o Painel, aguarde...' };
    } catch (error) {
        console.error('Unknown error occurred:', error);
        return { warning: 'Ocorreu um erro desconhecidoAlgo deu errado. Tente novamente mais tarde.' };
    };
}