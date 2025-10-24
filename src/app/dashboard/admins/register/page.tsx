import RegisterUserForm from '@/app/dashboard/admins/form-register-user';
import RegisterUserBreadcrumb from '@/components/breadcrumbs/register-user-breadcrumb';
import { Metadata } from 'next';

export const generateMetadata = async (): Promise<Metadata> => {
  return {
    title: 'Cadastrar Usuário'
  };
};

export default async function RegisterUserPage() {
  return (
    <>
      <RegisterUserBreadcrumb />
      <div className="flex gap-4 rounded-xl p-4">
        <RegisterUserForm valueButton="Cadastrar" />
      </div>
    </>
  );
}