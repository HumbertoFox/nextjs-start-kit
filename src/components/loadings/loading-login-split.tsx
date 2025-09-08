'use client';

import { Skeleton } from '@/components/ui/skeleton';

export default function LoadingLoginSplit() {
    return (
        <div className="relative grid h-dvh flex-col items-center justify-center px-8 sm:px-0 lg:max-w-none lg:grid-cols-2 lg:px-0">
            <div className="bg-muted relative hidden h-full flex-col p-10 text-white lg:flex dark:border-r">
                <div className="flex items-center gap-2">
                    <Skeleton className="size-10 rounded-full" />
                    <Skeleton className="h-4 w-40" />
                </div>

                <div className="flex items-center justify-center h-full z-10">
                    <Skeleton className="size-50 rounded-full" />
                </div>

                <div className="flex flex-col gap-3 mt-auto">
                    <Skeleton className="h-4 w-80" />
                    <Skeleton className="h-3 w-20" />
                </div>
            </div>
            <div className="w-full lg:p-8">
                <div className="mx-auto flex w-full flex-col justify-center space-y-6 sm:w-[350px]">
                    <div className="grid justify-items-center gap-4">
                        <Skeleton className="h-5 w-64" />
                        <Skeleton className="h-3.5 w-80" />
                    </div>

                    <div className="grid gap-2 mb-6">
                        <Skeleton className="h-3.5 w-32" />
                        <Skeleton className="h-9 w-full" />
                    </div>

                    <div className="grid gap-2">
                        <div className="flex justify-between">
                            <Skeleton className="h-3.5 w-25" />
                            <Skeleton className="h-3.5 w-30" />
                        </div>
                        <Skeleton className="h-9 w-full" />
                    </div>

                    <div className="grid justify-items-center gap-8 pt-4">
                        <Skeleton className="h-9 w-full" />
                    </div>
                </div>
            </div>
        </div>
    );
}