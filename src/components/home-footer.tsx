'use client';

import Image from 'next/image';
import gsap from 'gsap';
import { useEffect, useRef } from 'react';

export default function HomeFooterComponent() {
    const containerRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        const ctx = gsap.context(() => {
            gsap.fromTo('.link-item', {
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
        }, containerRef);

        return () => ctx.revert();
    }, []);
    return (
        <footer
            ref={containerRef}
            className="row-start-3 flex gap-[24px] flex-wrap items-center justify-center"
        >
            <a
                className="link-item flex items-center gap-2 hover:underline hover:underline-offset-4 opacity-0"
                href="https://nextjs.org/learn?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
                target="_blank"
                rel="noopener noreferrer"
            >
                <Image
                    aria-hidden
                    src="/file.svg"
                    alt="File icon"
                    width={16}
                    height={16}
                />
                Aprender
            </a>
            <a
                className="link-item flex items-center gap-2 hover:underline hover:underline-offset-4 opacity-0"
                href="https://vercel.com/templates?framework=next.js&utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
                target="_blank"
                rel="noopener noreferrer"
            >
                <Image
                    aria-hidden
                    src="/window.svg"
                    alt="Window icon"
                    width={16}
                    height={16}
                />
                Exemplos
            </a>
            <a
                className="link-item flex items-center gap-2 hover:underline hover:underline-offset-4 opacity-0"
                href="https://nextjs.org?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
                target="_blank"
                rel="noopener noreferrer"
            >
                <Image
                    aria-hidden
                    src="/globe.svg"
                    alt="Globe icon"
                    width={16}
                    height={16}
                />
                Ir para nextjs.org →
            </a>
        </footer>
    );
}