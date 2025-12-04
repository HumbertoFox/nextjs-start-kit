'use server';

import { put } from '@vercel/blob';
import { FormStateCreateUpdateAdminUser, getSignUpUpdateSchema } from '@/lib/definitions';
import prisma from '@/lib/prisma';
import * as bcrypt from 'bcrypt-ts';
import z from 'zod';
import sharp from 'sharp';
import { revalidatePath } from 'next/cache';

const MAX_FILE_SIZE = 512 * 1024;
const MAX_DIMENSION = 512;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

export async function createUpdateAdminUser(state: FormStateCreateUpdateAdminUser, formData: FormData): Promise<FormStateCreateUpdateAdminUser> {
    const schema = getSignUpUpdateSchema(formData);

    const validatedFields = schema.safeParse({
        name: formData.get('name') as string,
        email: (formData.get('email') as string)?.toLowerCase().trim(),
        password: formData.get('password') as string,
        role: formData.get('role') as string,
        password_confirmation: formData.get('password_confirmation') as string
    });

    const id = formData.get('id') as string | undefined;
    const file = formData.get('file') as File | null;

    function revalidatePaths(role: string) {
        role === 'ADMIN'
            ? revalidatePath('/dashboard/admins')
            : revalidatePath('/dashboard/admins/users');
    };

    if (!validatedFields.success) return { errors: z.flattenError(validatedFields.error).fieldErrors };

    const {
        name,
        email,
        password,
        role
    } = validatedFields.data;

    try {
        const hashedPassword = password ? await bcrypt.hash(password, 12) : undefined;

        let imageUrl: string | undefined;

        if (file && file.size > 0) {
            if (!ALLOWED_TYPES.includes(file.type)) return { errors: { image: ['Apenas JPEG, PNG ou WebP são permitidas.'] } };

            if (file.size > MAX_FILE_SIZE) return { errors: { image: ['A imagem não pode ultrapassar 512 KB.'] } };

            try {
                const buffer = Buffer.from(await file.arrayBuffer());
                const metadata = await sharp(buffer).metadata();
                const { width, height } = metadata;
                if (width > MAX_DIMENSION || height > MAX_DIMENSION) return { errors: { image: [`A imagem não pode exceder 512x512px (atual: ${width}x${height})`] } };
            } catch {
                return { errors: { image: ['Falha ao ler a imagem.'] } };
            }

            const uniqueFileName = `${crypto.randomUUID()}-${file.name}`;
            const blob = await put(`avatars/${uniqueFileName}`, file, {
                access: 'public',
            });

            imageUrl = blob.url;
        }

        if (id) {
            const userInDb = await prisma.user.findUnique({
                where: {
                    id
                }
            });

            if (!userInDb || userInDb.deletedAt) return { message: false };

            const existingUser = await prisma.user.findUnique({
                where: {
                    email
                }
            });

            if (existingUser && existingUser.id !== id) return { errors: { email: ['Este e-mail já está em uso!'] } };

            const hasChanges =
                userInDb.name !== name ||
                userInDb.email !== email ||
                userInDb.role !== role ||
                (hashedPassword && userInDb.password !== hashedPassword);

            if (!hasChanges) return { message: false };

            const updateUser = await prisma.user.update({
                where: {
                    id
                },
                data: {
                    name,
                    email,
                    role,
                    ...(hashedPassword && { password: hashedPassword }),
                    ...(imageUrl && { image: imageUrl }),
                }
            });

            revalidatePaths(updateUser.role);

            return { message: true };
        } else {
            const existingUser = await prisma.user.findFirst({
                where: {
                    email
                }
            });

            if (existingUser) return { errors: { email: ['Este e-mail já está em uso!'] } };

            const newUser = await prisma.user.create({
                data: {
                    name,
                    email,
                    role,
                    password: hashedPassword!,
                    ...(imageUrl && { image: imageUrl }),
                }
            });

            revalidatePaths(newUser.role);

            return { message: true };
        }
    } catch (error) {
        console.error(error);
        return { message: false };
    }
}