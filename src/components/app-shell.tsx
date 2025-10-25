'use client';

import { SidebarProvider } from '@/components/ui/sidebar';

interface AppShellProps {
    children: React.ReactNode;
    variant?: 'header' | 'sidebar';
    sidebarOpen?: boolean;
};

export function AppShell({ children, variant = 'header', sidebarOpen = true }: AppShellProps) {
    if (variant === 'header') {
        return <SidebarProvider defaultOpen={sidebarOpen} className="flex min-h-screen w-full flex-col">{children}</SidebarProvider>;
    }

    return <SidebarProvider defaultOpen={sidebarOpen}>{children}</SidebarProvider>;
}
