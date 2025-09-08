import prisma from '@/lib/prisma';
import RegisterAdmin from './form-register-admin';
import { redirect } from 'next/navigation';
import { Metadata } from 'next';

export const generateMetadata = async (): Promise<Metadata> => {
  return {
    title: 'Cadastrar Administrador'
  };
};
export default async function Register() {
  const isUserAdmin = await prisma.user.findMany({ where: { role: 'ADMIN' } });
  if (isUserAdmin.length > 0) redirect('/dashboard');
  return <RegisterAdmin />;
}