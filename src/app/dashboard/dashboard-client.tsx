'use client';

import { useEffect } from 'react';
import { useBreadcrumbs } from '@/context/breadcrumb-context';
import { PlaceholderPattern } from '@/components/ui/placeholder-pattern';

export default function DashboardPageClient() {
    const { setBreadcrumbs } = useBreadcrumbs();
    useEffect(() => setBreadcrumbs([{ title: 'Painel', href: '/dashboard' }]), [setBreadcrumbs]);
    return (
        <div className="flex h-full flex-1 flex-col gap-4 rounded-xl p-4">
            <div className="grid auto-rows-min gap-4 md:grid-cols-3">
                {[...Array(3)].map((_, index) => (
                    <div key={index} className="border-sidebar-border/70 dark:border-sidebar-border relative aspect-video overflow-hidden rounded-xl border">
                        <PlaceholderPattern className="absolute inset-0 size-full stroke-neutral-900/20 dark:stroke-neutral-100/20" />
                    </div>
                ))}
            </div>
            <div className="border-sidebar-border/70 dark:border-sidebar-border relative min-h-[100vh] flex-1 overflow-hidden rounded-xl border md:min-h-min">
                <PlaceholderPattern className="absolute inset-0 size-full stroke-neutral-900/20 dark:stroke-neutral-100/20" />
            </div>
        </div>
    );
}