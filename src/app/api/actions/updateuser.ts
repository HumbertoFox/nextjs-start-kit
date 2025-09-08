'use server';

import { getUser } from '@/lib/dal';
import { FormStateUserUpdate, updateUserSchema } from '@/lib/definitions';
import prisma from '@/lib/prisma';
import { redirect } from 'next/navigation';

export async function updateUser(state: FormStateUserUpdate, formData: FormData): Promise<FormStateUserUpdate> {
    const validatedFields = updateUserSchema.safeParse({
        name: formData.get('name') as string,
        email: formData.get('email') as string,
    });

    if (!validatedFields.success) return { errors: validatedFields.error.flatten().fieldErrors };

    const { name, email } = validatedFields.data;
    const sessionUser = await getUser();

    if (!sessionUser?.id) return redirect('/');

    const emailInUse = await prisma.user.findUnique({ where: { email } });

    if (emailInUse && emailInUse.id !== sessionUser.id) return { errors: { email: ['Este e-mail já está em uso'] } };

    const dataToUpdate: { name?: string; email?: string } = {};
    if (sessionUser.name !== name) dataToUpdate.name = name;
    if (sessionUser.email !== email) dataToUpdate.email = email;

    if (Object.keys(dataToUpdate).length === 0) return { message: 'No changes made.' };

    await prisma.user.update({ where: { id: sessionUser.id }, data: dataToUpdate });

    return { success: true };
}