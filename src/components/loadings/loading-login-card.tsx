'use client';

import { Skeleton } from '@/components/ui/skeleton';
import { Card } from '../ui/card';

export default function LoadingLoginCard() {
    return (
        <div className="bg-muted flex min-h-svh flex-col items-center justify-center gap-6 p-6 md:p-10">
            <div className="flex w-full max-w-md flex-col justify-center gap-6">

                <Skeleton className="flex h-9 w-9 mx-auto rounded-full" />

                <div className="flex flex-col gap-6">
                    <Card className="w-full max-w-[448px] max-h-[430px] h-screen rounded-xl">
                        <div className="grid justify-items-center gap-4 pt-10">
                            <Skeleton className="h-5 w-64" />
                            <Skeleton className="h-3.5 w-80" />
                        </div>

                        <div className="flex flex-col gap-6 px-10 py-8">
                            <div className="grid gap-2">
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

                            <div className="grid justify-items-center gap-7 pt-5">
                                <Skeleton className="h-9 w-full" />
                            </div>
                        </div>
                    </Card>
                </div>
            </div>
        </div>
    );
}