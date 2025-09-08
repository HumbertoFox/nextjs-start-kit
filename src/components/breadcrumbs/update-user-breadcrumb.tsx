'use client';

import { useEffect } from 'react';
import { useBreadcrumbs } from '@/context/breadcrumb-context';
import { type User } from '@/types';

export default function UpdateUserBreadcrumb({ user }: { user: User }) {
    const { setBreadcrumbs } = useBreadcrumbs();
    useEffect(() => {
        setBreadcrumbs([
            { title: 'Painel', href: '/dashboard' },
            { title: 'Administradores', href: '/dashboard/admins' },
            { title: user?.name ? `Atualizar ${user.name}` : 'Atualizar usuário', href: `/dashboard/admins/update/${user.id}` }
        ]);
    }, [setBreadcrumbs, user]);

    return null;
}