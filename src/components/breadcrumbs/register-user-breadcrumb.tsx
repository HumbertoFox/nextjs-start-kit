'use client';

import { useEffect } from 'react';
import { useBreadcrumbs } from '@/context/breadcrumb-context';

export default function RegisterUserBreadcrumb() {
    const { setBreadcrumbs } = useBreadcrumbs();
    useEffect(() => {
        setBreadcrumbs([
            { title: 'Painel', href: '/dashboard' },
            { title: 'Administradores', href: '/dashboard/admins' },
            { title: 'Cadastrar', href: '/dashboard/admins/register' }
        ]);
    }, [setBreadcrumbs]);

    return null;
}