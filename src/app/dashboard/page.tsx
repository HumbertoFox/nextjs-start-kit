import { redirect } from 'next/navigation';
import prisma from '@/lib/prisma';
import DashboardPageClient from './dashboard-client';
import { getUser } from '@/lib/dal';
import { Metadata } from 'next';

export const generateMetadata = async (): Promise<Metadata> => {
  return {
    title: 'Painel'
  };
};

export default async function Dashboard() {
  const sessionUser = await getUser();
  const user = await prisma.user.findUnique({ where: { id: sessionUser?.id } });
  if (!sessionUser?.id || !user?.id) redirect('/login');
  return <DashboardPageClient />;
}