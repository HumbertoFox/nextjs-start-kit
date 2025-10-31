import { Button } from '@/components/ui/button';
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { reactivateAdminUserById } from '@/app/api/actions/reactivateadminuser';
import { Icon } from '@/components/ui/icon';
import { PlaceholderPattern } from '@/components/ui/placeholder-pattern';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { UserLock, UserRoundPen, UserRoundX } from 'lucide-react';
import Link from 'next/link';
import AdminsBreadcrumb from '@/components/breadcrumbs/admins-breadcrumb';
import prisma from '@/lib/prisma';
import { getUser } from '@/lib/dal';
import { deleteUserById } from '@/app/api/actions/deleteadminuser';
import { Metadata } from 'next';

export const generateMetadata = async (): Promise<Metadata> => {
    return {
        title: 'Administradores'
    };
};

export default async function Admins() {
    const session = await getUser();
    const loggedAdmin = session?.id;
    const admins = await prisma.user.findMany({
        where: {
            role: 'ADMIN',
        },
        select: {
            id: true,
            name: true,
            email: true,
            deletedAt: true,
        }
    });
    return (
        <>
            <AdminsBreadcrumb />
            <div className="flex h-full flex-1 flex-col gap-4 rounded-xl p-4">
                <div className="grid auto-rows-min gap-4 md:grid-cols-3">
                    {[...Array(3)].map((_, index) => (
                        <div key={index} className="border-sidebar-border/70 dark:border-sidebar-border relative aspect-video overflow-hidden rounded-xl border">
                            <PlaceholderPattern className="absolute inset-0 size-full stroke-neutral-900/20 dark:stroke-neutral-100/20" />
                        </div>
                    ))}
                </div>
                <div className="border-sidebar-border/70 dark:border-sidebar-border relative min-h-screen flex-1 overflow-hidden rounded-xl border md:min-h-min">
                    <Table className="w-full text-center">
                        <TableHeader>
                            <TableRow className="cursor-default">
                                <TableHead className="text-center">Nº</TableHead>
                                <TableHead className="text-center max-lg:hidden">Cód.</TableHead>
                                <TableHead className="text-center max-lg:hidden">Nome</TableHead>
                                <TableHead className="text-center">E-mail</TableHead>
                                <TableHead className="text-center">Ações</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {admins.length === 0 && (
                                <TableRow className="text-red-600 cursor-default">
                                    <TableCell colSpan={5}>Não há outros administradores</TableCell>
                                </TableRow>
                            )}
                            {admins.map((admin, index) => (
                                <TableRow key={index} className="cursor-default">
                                    <TableCell>{index + 1}</TableCell>
                                    <TableCell className="max-lg:hidden">{admin.id}</TableCell>
                                    <TableCell className="max-lg:hidden">{admin.name}</TableCell>
                                    <TableCell>{admin.email}</TableCell>
                                    <TableCell className="flex justify-evenly items-center my-1">
                                        {!admin.deletedAt ? (
                                            <>
                                                <Link
                                                    href={admin.id === loggedAdmin ? '/dashboard/settings/profile' : `/dashboard/admins/${admin.id}/update`}
                                                    title={`Atualizar ${admin.name}`}
                                                >
                                                    <Icon
                                                        iconNode={UserRoundPen}
                                                        aria-label={`Atualizar ${admin.name}`}
                                                        className="size-6 text-yellow-600 hover:text-yellow-500 duration-300"
                                                    />
                                                </Link>

                                                <Dialog key={admin.id}>
                                                    <DialogTrigger asChild>
                                                        {admin.id !== loggedAdmin && (
                                                            <button type="button" title={`Excluir ${admin.name}`}>
                                                                <Icon
                                                                    iconNode={UserRoundX}
                                                                    aria-label={`Excluir ${admin.name}`}
                                                                    className="size-6 text-red-600 cursor-pointer hover:text-red-500 duration-300"
                                                                />
                                                            </button>
                                                        )}
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
                                                                <input type="hidden" name="userId" value={admin.id} />
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
                                            </>
                                        ) : (
                                            <form action={reactivateAdminUserById}>
                                                <input type="hidden" name="userId" value={admin.id} />
                                                <button
                                                    type="submit"
                                                    title={`Ativar ${admin.name}`}
                                                    className="cursor-pointer"
                                                >
                                                    <Icon
                                                        iconNode={UserLock}
                                                        aria-label={`Arivar ${admin.name}`}
                                                        className="size-6 text-red-600 hover:text-green-500 duration-300"
                                                    />
                                                </button>
                                            </form>
                                        )}
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            </div>
        </>
    );
}