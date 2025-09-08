'use client';

import AppearanceTabs from '@/components/appearance-tabs';
import HeadingSmall from '@/components/heading-small';
import { useBreadcrumbs } from '@/context/breadcrumb-context';
import { useEffect } from 'react';

export default function AppearancePageClient() {
    const { setBreadcrumbs } = useBreadcrumbs();
    useEffect(() => {
        setBreadcrumbs([
            { title: 'Painel', href: '/dashboard' },
            { title: 'Configurações de Aparência', href: '/dashboard/settings/appearance' }
        ]);
    }, [setBreadcrumbs]);
    return (
        <>
            <div className="space-y-6">
                <HeadingSmall
                    title="Configurações de aparência"
                    description="Atualize as configurações de aparência da sua conta"
                />
                <AppearanceTabs />
            </div>
        </>
    );
}