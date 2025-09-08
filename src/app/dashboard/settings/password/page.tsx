import { Metadata } from 'next';
import PasswordPageClient from './password-client';

export const generateMetadata = async (): Promise<Metadata> => {
    return {
        title: 'Atualizar senha'
    };
}

export default function Password() {
    return <PasswordPageClient />;
}