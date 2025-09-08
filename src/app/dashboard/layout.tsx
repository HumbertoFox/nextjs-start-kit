import { BreadcrumbProvider } from '@/context/breadcrumb-context';
import AppLayout from '@/components/layouts/app-layout';
import { ReactNode } from 'react';

export default function DashboardLayout({ children }: { children: ReactNode }) {
    return (
        <BreadcrumbProvider>
            <AppLayout>{children}</AppLayout>
        </BreadcrumbProvider>
    );
}