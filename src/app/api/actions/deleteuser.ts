'use server';

import { getUser } from '@/lib/dal';
import { deleteUserSchema, FormStateUserDelete } from '@/lib/definitions';
import prisma from '@/lib/prisma';
import * as bcrypt from 'bcrypt-ts';

export async function deleteUser(state: FormStateUserDelete, formData: FormData): Promise<FormStateUserDelete> {
    const validatedFields = deleteUserSchema.safeParse({ password: formData.get('password') as string });

    if (!validatedFields.success) return { errors: validatedFields.error.flatten().fieldErrors };

    const { password } = validatedFields.data;
    const sessionUser = await getUser();

    if (!sessionUser?.id) return { message: false };

    const existingUser = await prisma.user.findUnique({ where: { id: sessionUser.id } });

    if (!existingUser) return { message: false };

    const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);
    if (!isPasswordCorrect) return { errors: { password: ['Senha incorreta'] } };

    await prisma.user.update({ where: { id: sessionUser.id }, data: { deletedAt: new Date() } });

    return { message: true };
}