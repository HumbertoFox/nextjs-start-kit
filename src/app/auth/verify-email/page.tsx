import { Suspense } from 'react';
import VerifyEmailClient from './verify-email-client';
import LoadingVerifyEmail from '@/components/loadings/loading-verify-email';

export default function VerifyEmailPage() {
    return (
        <Suspense fallback={<LoadingVerifyEmail />}>
            <VerifyEmailClient />
        </Suspense>
    );
}