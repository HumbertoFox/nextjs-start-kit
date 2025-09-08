import AppearancePageClient from './appearance-client';
import { Metadata } from 'next';

export const generateMetadata = async (): Promise<Metadata> => {
    return {
        title: 'Atualizar Aparência'
    };
};

export default function Appearance() {
    return <AppearancePageClient />;
}