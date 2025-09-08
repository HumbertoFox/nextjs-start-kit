import { Suspense } from 'react';
import ResetPasswordClient from './reset-password-client';
import LoadingResetPassword from '@/components/loadings/loading-reset-password';

export default function ResetPasswordPage() {
    return (
        <Suspense fallback={<LoadingResetPassword />}>
            <ResetPasswordClient />
        </Suspense>
    );
}