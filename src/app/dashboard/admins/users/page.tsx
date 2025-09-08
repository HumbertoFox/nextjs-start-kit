import { deleteUserById } from '@/app/api/actions/deleteadminuser';
import UsersBreadcrumb from '@/components/breadcrumbs/users-breadcrumb';
import { Button } from '@/components/ui/button';
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Icon } from '@/components/ui/icon';
import { Pagination, PaginationContent, PaginationItem, PaginationLink, PaginationNext, PaginationPrevious } from '@/components/ui/pagination';
import { PlaceholderPattern } from '@/components/ui/placeholder-pattern';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import prisma from '@/lib/prisma';
import { UserPen, UserX } from 'lucide-react';
import { Metadata } from 'next';
import Link from 'next/link';

export const generateMetadata = async (): Promise<Metadata> => {
    return {
        title: 'Usuários'
    };
};

const pageSize = 10;

function getVisiblePages(current: number, total: number): (number | string)[] {
    const delta = 2;
    const range: (number | string)[] = [];

    const start = Math.max(2, current - delta);
    const end = Math.min(total - 1, current + delta);

    range.push(1);

    if (start > 2) {
        range.push('...');
    }

    for (let i = start; i <= end; i++) {
        range.push(i);
    }

    if (end < total - 1) {
        range.push('...');
    }

    if (total > 1) {
        range.push(total);
    }

    return range;
}

export default async function Users(props: { searchParams?: Promise<{ page?: number; }>; }) {
    const searchParams = await props.searchParams;
    const currentPage = searchParams?.page || 1;
    const [users, totalUsers] = await Promise.all([
        prisma.user.findMany({
            where: { role: 'USER', deletedAt: null },
            select: { id: true, name: true, email: true },
            skip: (currentPage - 1) * pageSize,
            take: pageSize,
        }),
        prisma.user.count({
            where: { role: 'USER', deletedAt: null },
        }),
    ]);
    const totalPages = Math.ceil(totalUsers / pageSize);
    return (
        <>
            <UsersBreadcrumb />
            <div className="flex h-full flex-1 flex-col gap-4 rounded-xl p-4">
                <div className="grid auto-rows-min gap-4 md:grid-cols-3">
                    {[...Array(3)].map((_, index) => (
                        <div key={index} className="border-sidebar-border/70 dark:border-sidebar-border relative aspect-video overflow-hidden rounded-xl border">
                            <PlaceholderPattern className="absolute inset-0 size-full stroke-neutral-900/20 dark:stroke-neutral-100/20" />
                        </div>
                    ))}
                </div>
                <div className="border-sidebar-border/70 dark:border-sidebar-border relative min-h-[100vh] flex-1 overflow-hidden rounded-xl border md:min-h-min">
                    <Table className="w-full text-center">
                        <TableHeader>
                            <TableRow className="cursor-default">
                                <TableHead className="text-center">Nº</TableHead>
                                <TableHead className="text-center">Cód.</TableHead>
                                <TableHead className="text-center">Nome</TableHead>
                                <TableHead className="text-center">E-mail</TableHead>
                                <TableHead className="text-center">Ações</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {users.length === 0 && (
                                <TableRow className="text-red-600 cursor-default">
                                    <TableCell colSpan={5}>Não há nenhum usuário registrado</TableCell>
                                </TableRow>
                            )}
                            {users.map((user, index) => (
                                <TableRow key={user.id} className="cursor-default">
                                    <TableCell>{(currentPage - 1) * 10 + index + 1}</TableCell>
                                    <TableCell>{user.id}</TableCell>
                                    <TableCell>{user.name}</TableCell>
                                    <TableCell>{user.email}</TableCell>
                                    <TableCell className="flex justify-evenly items-center my-1">
                                        <Link
                                            href={`/dashboard/admins/${user.id}/update`}
                                            title={`Atualizar ${user.name}`}
                                        >
                                            <Icon
                                                iconNode={UserPen}
                                                aria-label={`Atualizar ${user.name}`}
                                                className="size-6 text-yellow-600 hover:text-yellow-500 duration-300"
                                            />
                                        </Link>

                                        <Dialog>
                                            <DialogTrigger asChild>
                                                <button
                                                    type="button"
                                                    title={`Excluir ${user.name}`}
                                                >
                                                    <Icon
                                                        iconNode={UserX}
                                                        aria-label={`Excluir ${user.name}`}
                                                        className="size-6 text-red-600 cursor-pointer hover:text-red-500 duration-300"
                                                    />
                                                </button>
                                            </DialogTrigger>
                                            <DialogContent>
                                                <DialogTitle>
                                                    você tem certeza?
                                                </DialogTitle>
                                                <DialogDescription>
                                                    Depois de confirmar, você não poderá reverter esta ação!
                                                </DialogDescription>
                                                <DialogFooter>
                                                    <DialogClose asChild>
                                                        <Button type="button" variant="secondary">
                                                            Cancelar
                                                        </Button>
                                                    </DialogClose>
                                                    <form action={deleteUserById}>
                                                        <input type="hidden" name="userId" value={user.id} />
                                                        <Button
                                                            type="submit"
                                                            variant="destructive"
                                                        >
                                                            Sim, Excluir!
                                                        </Button>
                                                    </form>
                                                </DialogFooter>
                                            </DialogContent>
                                        </Dialog>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            </div>
            <Pagination className="pb-2.5">
                <PaginationContent>
                    <PaginationItem>
                        <PaginationPrevious
                            href={currentPage > 1 ? `?page=${currentPage - 1}` : '#'}
                            aria-disabled={currentPage <= 1}
                            className={currentPage <= 1 ? 'pointer-events-none opacity-50' : ''}
                        />
                    </PaginationItem>
                    {getVisiblePages(currentPage, totalPages).map((page, index) => (
                        <PaginationItem key={index}>
                            {page === '...' ? (
                                <PaginationLink
                                    href="#"
                                    aria-disabled
                                    className="pointer-events-none opacity-50"
                                >
                                    ...
                                </PaginationLink>
                            ) : (
                                <PaginationLink
                                    href={`?page=${page}`}
                                    isActive={currentPage === page}
                                >
                                    {page}
                                </PaginationLink>
                            )}
                        </PaginationItem>
                    ))}
                    <PaginationItem>
                        <PaginationNext
                            href={currentPage < totalPages ? `?page=${currentPage + 1}` : '#'}
                            aria-disabled={currentPage >= totalPages}
                            className={currentPage >= totalPages ? 'pointer-events-none opacity-50' : ''}
                        />
                    </PaginationItem>
                </PaginationContent>
            </Pagination>
        </>
    );
}
