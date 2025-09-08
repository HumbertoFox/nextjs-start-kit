import { getUser } from '@/lib/dal';
import ProfilePageClient from './profile-client';
import { Metadata } from 'next';

export const generateMetadata = async (): Promise<Metadata> => {
    return {
        title: 'Atualizar perfil'
    };
};

export default async function Profile() {
    const user = await getUser();
    if (!user) return null;
    return (
        <ProfilePageClient name={user.name} email={user.email} mustVerifyEmail={!user.emailVerified} />
    );
}