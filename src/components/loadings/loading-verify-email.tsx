'use client';

import { Skeleton } from '@/components/ui/skeleton';

export default function LoadingVerifyEmail() {
    return (
        <div className="flex flex-col items-center justify-center gap-6 w-full max-[1440px] min-h-screen space-y-3">
            <Skeleton className="size-10 rounded-full" />
            <div className="grid justify-items-center gap-4">
                <Skeleton className="h-5 w-40" />
                <div className="flex flex-col items-center gap-2">
                    <Skeleton className="h-3.5 w-96" />
                    <Skeleton className="h-3.5 w-28" />
                </div>
            </div>

            <div className="grid gap-6 space-y-2">
                <div className="grid gap-2 justify-center">
                    <Skeleton className="h-3.5 w-36" />
                </div>

                <div className="grid gap-2">
                    <Skeleton className="h-9 w-48" />
                </div>
                <div className="grid justify-items-center gap-2">
                    <Skeleton className="h-3.5 w-16" />
                </div>
            </div>
        </div>
    );
}