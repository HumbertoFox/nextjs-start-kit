'use server';

import { getUser } from '@/lib/dal';
import { FormStatePasswordUpdate, passwordUpdateSchema } from '@/lib/definitions';
import prisma from '@/lib/prisma';
import { compare, hash } from 'bcrypt-ts';
import { redirect } from 'next/navigation';

export async function updatePassword(state: FormStatePasswordUpdate, formData: FormData): Promise<FormStatePasswordUpdate> {
    const validatedFields = passwordUpdateSchema.safeParse({
        current_password: formData.get('current_password') as string,
        password: formData.get('password') as string,
        password_confirmation: formData.get('password_confirmation') as string
    });

    if (!validatedFields.success) return { errors: validatedFields.error.flatten().fieldErrors, };

    const { current_password, password } = validatedFields.data;

    const sessionUser = await getUser();

    if (!sessionUser?.id) return redirect('/');

    const authUser = await prisma.user.findUnique({ where: { id: sessionUser.id } });

    if (!authUser) return redirect('/');

    const isValid = await compare(current_password, authUser.password);

    if (!isValid) return { errors: { current_password: ['A senha atual está incorreta'] } };

    if (current_password === password) return { errors: { password: ['A nova senha não pode ser igual à antiga'] } };

    const hashedPassword = await hash(password, 12);

    await prisma.user.update({ where: { id: sessionUser.id }, data: { password: hashedPassword }, });

    return { message: true };
}