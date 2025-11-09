'use server';

import { put } from '@vercel/blob';
import { createAdminSchema, FormStateCreateAdmin } from '@/lib/definitions';
import prisma from '@/lib/prisma';
import { createSession } from '@/lib/session';
import * as bcrypt from 'bcrypt-ts';
import z from 'zod';
import sharp from 'sharp';

const MAX_FILE_SIZE = 512 * 1024;
const MAX_DIMENSION = 512;
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

export async function createAdmin(state: FormStateCreateAdmin, formData: FormData): Promise<FormStateCreateAdmin> {
    const validatedFields = createAdminSchema.safeParse({
        name: formData.get('name') as string,
        email: (formData.get('email') as string)?.toLowerCase().trim(),
        password: formData.get('password') as string,
        password_confirmation: formData.get('password_confirmation') as string
    });

    const file = formData.get('file') as File | null;

    if (!validatedFields.success) return { errors: z.flattenError(validatedFields.error).fieldErrors };

    const { name, email, password } = validatedFields.data;

    try {
        const hashedPassword = await bcrypt.hash(password, 12);

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
                token: process.env.BLOB_READ_WRITE_TOKEN,
            });

            imageUrl = blob.url;
        }

        const user = await prisma.user.create({
            data: {
                name,
                email,
                role: 'ADMIN',
                password: hashedPassword,
                ...(imageUrl && { image: imageUrl }),
            }
        });

        await createSession(user.id, user.role);

        return { message: true };
    } catch (error) {
        console.error(error);
        return { warning: 'Algo deu errado. Tente novamente mais tarde.' };
    }
}