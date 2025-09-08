'use client';

import { NavFooter } from '@/components/nav-footer';
import { NavMain } from '@/components/nav-main';
import { NavUser } from '@/components/nav-user';
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem } from '@/components/ui/sidebar';
import { User, type NavItem } from '@/types';
import { BookOpen, Folder, LayoutGrid, UserRoundCog, UserRoundPlus, UsersRound } from 'lucide-react';
import AppLogo from './app-logo';
import Link from 'next/link';

export function AppSidebar({ user }: { user: User }) {
    const isAdmin = user.role === 'ADMIN';

    const mainNavItems: NavItem[] = [
        { title: 'Painel', href: '/dashboard', icon: LayoutGrid, },
    ];
    const adminNavItems: NavItem[] = [
        { title: 'Administradores', href: '/dashboard/admins', icon: UserRoundCog },
        { title: 'Usuários', href: '/dashboard/admins/users', icon: UsersRound },
        { title: 'Cadastrar', href: '/dashboard/admins/register', icon: UserRoundPlus },
    ];
    const footerNavItems: NavItem[] = [
        { title: 'Repositório', href: 'https://github.com/HumbertoFox/next-auth-start-kit', icon: Folder, },
        { title: 'Desenvolvedor', href: 'https://betofoxnet-info.vercel.app/', icon: BookOpen, },
    ];

    const navItems = isAdmin ? [...mainNavItems, ...adminNavItems] : mainNavItems;
    return (
        <Sidebar collapsible="icon" variant="inset">
            <SidebarHeader>
                <SidebarMenu>
                    <SidebarMenuItem>
                        <SidebarMenuButton size="lg" asChild>
                            <Link href="/dashboard" prefetch>
                                <AppLogo />
                            </Link>
                        </SidebarMenuButton>
                    </SidebarMenuItem>
                </SidebarMenu>
            </SidebarHeader>

            <SidebarContent>
                <NavMain items={navItems} />
            </SidebarContent>

            <SidebarFooter>
                <NavFooter items={footerNavItems} className="mt-auto" />
                <NavUser user={user} />
            </SidebarFooter>
        </Sidebar>
    );
}
