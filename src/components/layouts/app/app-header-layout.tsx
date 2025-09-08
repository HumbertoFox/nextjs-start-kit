'use client';

import { AppContent } from '@/components/app-content';
import { AppHeader } from '@/components/app-header';
import { AppShell } from '@/components/app-shell';
import { User, type BreadcrumbItem } from '@/types';
import type { PropsWithChildren } from 'react';

export default function AppHeaderLayout({ children, user }: PropsWithChildren<{ breadcrumbs?: BreadcrumbItem[], user: User }>) {
    return (
        <AppShell>
            <AppHeader user={user} />
            <AppContent>{children}</AppContent>
        </AppShell>
    );
}
