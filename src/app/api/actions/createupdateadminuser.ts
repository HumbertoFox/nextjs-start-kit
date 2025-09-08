'use server';

import { FormStateCreateUpdateAdminUser, getSignUpUpdateSchema, } from '@/lib/definitions';
import prisma from '@/lib/prisma';
import * as bcrypt from 'bcrypt-ts';

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

    if (!validatedFields.success) return { errors: validatedFields.error.flatten().fieldErrors };

    const { name, email, password, role } = validatedFields.data;

    try {
        const hashedPassword = password ? await bcrypt.hash(password, 12) : undefined;

        if (id) {
            const userInDb = await prisma.user.findUnique({ where: { id } });

            if (!userInDb || userInDb.deletedAt) return { message: false };

            const hasChanges =
                userInDb.name !== name ||
                userInDb.email !== email ||
                userInDb.role !== role ||
                (hashedPassword && userInDb.password !== hashedPassword);

            if (!hasChanges) return { message: false };

            await prisma.user.update({ where: { id: id }, data: { name, email, role, ...(hashedPassword && { password: hashedPassword }) } });

            return { message: true };
        } else {
            const existingUser = await prisma.user.findFirst({ where: { email } });

            if (existingUser) return { errors: { email: ['Este e-mail já está em uso'] } };

            await prisma.user.create({ data: { name, email, role, password: hashedPassword! } });

            return { message: true };
        }
    } catch (error) {
        console.error(error);
        return { message: false };
    }
}