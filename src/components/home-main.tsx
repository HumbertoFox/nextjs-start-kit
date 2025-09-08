'use client';

import Image from 'next/image';
import gsap from 'gsap';
import { useEffect, useRef } from 'react';

export default function HomeMainComponent() {
    const containerRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        const ctx = gsap.context(() => {
            gsap.fromTo('.logo', {
                opacity: 0,
                scale: 0.5,
                rotate: -45
            }, {
                opacity: 1,
                scale: 1,
                rotate: 0,
                duration: 1.2,
                ease: 'elastic.out(1, 0.5)'
            });

            gsap.fromTo('.list-item', {
                opacity: 0,
                x: -50,
                rotation: -15
            }, {
                opacity: 1,
                x: 0,
                rotation: 0,
                duration: 1,
                ease: 'back.out(1.7)',
                stagger: 0.25,
                delay: 0.4
            });

            gsap.fromTo('.buttons', {
                opacity: 0,
                y: 80,
                scale: 0.8
            }, {
                opacity: 1,
                y: 0,
                scale: 1,
                duration: 1,
                ease: 'bounce.out',
                delay: 1
            });
        }, containerRef);

        return () => ctx.revert();
    }, []);
    return (
        <main
            ref={containerRef}
            className="flex flex-col gap-[32px] row-start-2 items-center sm:items-start max-w-[1440px]"
        >
            <div className="logo opacity-0">
                <Image
                    className="dark:invert"
                    src="/next.svg"
                    alt="Next.js logo"
                    width={180}
                    height={38}
                    priority
                />
            </div>
            <ol className="list-inside list-decimal text-sm/6 text-center sm:text-left font-[family-name:var(--font-geist-mono)]">
                <li className="list-item mb-2 tracking-[-.01em] opacity-0">
                    Comece editando&nbsp;
                    <code className="bg-black/[.05] dark:bg-white/[.06] px-1 py-0.5 rounded font-[family-name:var(--font-geist-mono)] font-semibold">
                        src/app/page.tsx
                    </code>
                    .
                </li>
                <li className="list-item tracking-[-.01em] opacity-0">
                    Salve e veja suas mudanças instantaneamente.
                </li>
            </ol>

            <div className="buttons flex gap-4 items-center flex-col sm:flex-row opacity-0">
                <a
                    className="rounded-full border border-solid border-transparent transition-colors flex items-center justify-center bg-foreground text-background gap-2 hover:bg-[#383838] dark:hover:bg-[#ccc] font-medium text-sm sm:text-base h-10 sm:h-12 px-4 sm:px-5 sm:w-auto"
                    href="https://vercel.com/new?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    <Image
                        className="dark:invert"
                        src="/vercel.svg"
                        alt="Vercel logomark"
                        width={20}
                        height={20}
                    />
                    Implantar agora
                </a>
                <a
                    className="rounded-full border border-solid border-black/[.08] dark:border-white/[.145] transition-colors flex items-center justify-center hover:bg-[#f2f2f2] dark:hover:bg-[#1a1a1a] hover:border-transparent font-medium text-sm text-center sm:text-base h-10 sm:h-12 px-4 sm:px-5 w-full sm:w-auto md:w-[158px]"
                    href="https://nextjs.org/docs?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    Leia nossa documentação
                </a>
            </div>
        </main>
    );
}