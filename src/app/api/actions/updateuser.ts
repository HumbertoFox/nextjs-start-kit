'use server';

import { getUser } from '@/lib/dal';
import { FormStateUserUpdate, updateUserSchema } from '@/lib/definitions';
import prisma from '@/lib/prisma';
import { redirect } from 'next/navigation';
import z from 'zod';
import { put, del } from '@vercel/blob';
import crypto from 'crypto';

const MAX_FILE_SIZE = 512 * 1024;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

export async function updateUser(state: FormStateUserUpdate, formData: FormData): Promise<FormStateUserUpdate> {
    const validatedFields = updateUserSchema.safeParse({
        name: formData.get('name') as string,
        email: formData.get('email') as string,
    });
    const file = formData.get('file') as File | null;

    if (!validatedFields.success) return { errors: z.flattenError(validatedFields.error).fieldErrors };

    const { name, email } = validatedFields.data;

    const sessionUser = await getUser();
    if (!sessionUser || !sessionUser?.id) return redirect('/');

    const emailInUse = await prisma.user.findUnique({
        where: {
            email
        }
    });

    if (emailInUse && emailInUse.id !== sessionUser.id) return { errors: { email: ['Este e-mail já está em uso'] } };

    const dataToUpdate: { name?: string; email?: string, image?: string | null } = {};
    if (sessionUser.name !== name) dataToUpdate.name = name;
    if (sessionUser.email !== email) dataToUpdate.email = email;

    if (file && file.size > 0) {
        if (!ALLOWED_TYPES.includes(file.type)) return { errors: { image: ['Apenas JPEG, PNG ou WebP são permitidas.'] } };

        if (file.size > MAX_FILE_SIZE) return { errors: { image: ['A imagem não pode ultrapassar 512 KB.'] } };

        try {
            if (sessionUser.image) {
                try {
                    await del(sessionUser.image);
                } catch (deleteErr) {
                    console.warn('Não foi possível deletar imagem anterior:', deleteErr);
                }
            }

            const uniqueFileName = `${crypto.randomUUID()}-${file.name}`;
            const blob = await put(`avatars/${uniqueFileName}`, file, {
                access: 'public',
            });

            if (blob.url) {
                dataToUpdate.image = blob.url;
            }
        } catch (error) {
            console.error('Erro ao enviar imagem:', error);
            return { errors: { image: ['Erro ao enviar imagem. Tente novamente.'] } };
        }
    }

    if (Object.keys(dataToUpdate).length === 0) return { message: 'No changes made.' };

    await prisma.user.update({
        where: {
            id: sessionUser.id
        },
        data: dataToUpdate
    });

    return { success: true };
}