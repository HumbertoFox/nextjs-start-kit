import 'server-only';
import { cache } from 'react';
import prisma from './prisma';
import { verifySession } from './session';

export const getUser = cache(async () => {
    const session = await verifySession();
    if (!session) return null;

    try {
        const user = await prisma.user.findUnique({
            where: { id: session.userId },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                emailVerified: true,
                image: true
            }
        });

        if (!user) return null;

        return user
    } catch (error) {
        console.log('Failed to fetch user', error)
        return null
    }
})