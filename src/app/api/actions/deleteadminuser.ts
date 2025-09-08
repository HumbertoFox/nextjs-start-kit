'use server';

import prisma from '@/lib/prisma';
import { revalidatePath } from 'next/cache';

export async function deleteUserById(formData: FormData) {
    const userId = formData.get('userId') as string;

    if (!userId) return;

    try {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) return;

        await prisma.user.update({ where: { id: userId }, data: { deletedAt: new Date() } });

        if (user?.role === 'ADMIN') {
            revalidatePath('/dashboard/admins');
        } else if (user?.role === 'USER') {
            revalidatePath('/dashboard/users');
        }
    } catch (error) {
        console.error('Error deleting user:', error);
    }
}