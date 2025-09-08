import { LucideIcon } from 'lucide-react';

export interface User {
    id: string;
    name: string;
    email: string;
    image?: string;
    emailVerified: Date | null;
    role: string;
    [key: string]: unknown;
}

export interface BreadcrumbItem {
    title: string;
    href: string;
}

export interface NavGroup {
    title: string;
    items: NavItem[];
}

export interface NavItem {
    title: string;
    href: string;
    icon?: LucideIcon | null;
    isActive?: boolean;
}