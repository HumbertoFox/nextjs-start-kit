'use client';

import { useEffect } from 'react';
import { useBreadcrumbs } from '@/context/breadcrumb-context';

export default function UsersBreadcrumb() {
    const { setBreadcrumbs } = useBreadcrumbs();
    useEffect(() => {
        setBreadcrumbs([
            { title: 'Painel', href: '/dashboard' },
            { title: 'Administradores', href: '/dashboard/admins' },
            { title: 'Usuários', href: '/dashboard/admins/users' }
        ]);
    }, [setBreadcrumbs]);

    return null;
}