'use client';

import { useEffect } from 'react';
import { useBreadcrumbs } from '@/context/breadcrumb-context';
import { type User } from '@/types';
import { useRouter } from 'next/navigation';

export default function UpdateUserBreadcrumb({ user }: { user: User }) {
    const router = useRouter();
    const { setBreadcrumbs } = useBreadcrumbs();
    useEffect(() => {
        if (user) {
            const base = [
                { title: 'Painel', href: '/dashboard' },
                { title: 'Administradores', href: '/dashboard/admins' },
            ];

            const nameOrDefault = user?.name ? `Atualizar ${user.name}` : 'Atualizar usuário';
            const updateCrumb = { title: nameOrDefault, href: `/dashboard/admins/update/${user.id}` };

            const crumbs =
                user.role === 'USER'
                    ? [...base, { title: 'Usuários', href: '/dashboard/admins/users' }, updateCrumb]
                    : [...base, updateCrumb];

            setBreadcrumbs(crumbs);
        } else {
            router.back();
        };
    }, [setBreadcrumbs, user]);

    return null;
}