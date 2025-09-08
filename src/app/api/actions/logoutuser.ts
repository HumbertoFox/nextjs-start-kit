'use server';

import { cookies } from 'next/headers';

export async function deleteSession() {
    const session = (await cookies()).get('sessionAuth');

    if (session) {
        (await cookies()).delete('sessionAuth');
        return true;
    };
    return false;
}