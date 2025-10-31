'use server';

import prisma from '@/lib/prisma';
import { revalidatePath } from 'next/cache';

export async function reactivateAdminUserById(formData: FormData) {
    const userId = formData.get('userId') as string;

    if (!userId) return;

    const user = await prisma.user.update({
        where: { id: userId },
        data: { deletedAt: null },
    });

    user.role === 'ADMIN'
        ? revalidatePath('/dashboard/admins')
        : revalidatePath('/dashboard/admins/users');
}