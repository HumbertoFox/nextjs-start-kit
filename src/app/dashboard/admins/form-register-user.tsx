'use client';

import { Eye, EyeClosed, LoaderCircle } from 'lucide-react';
import { ChangeEvent, FormEvent, startTransition, useActionState, useEffect, useState } from 'react';
import InputError from '@/components/input-error';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Icon } from '@/components/ui/icon';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useRouter } from 'next/navigation';
import { createUpdateAdminUser } from '@/app/api/actions/createupdateadminuser';
import Image from 'next/image';
import { handleImageChange } from '@/lib/handleimagechange';

type UserProps = {
    id: string;
    name: string;
    email: string;
    role: string;
    image?: string;
};

type RegisterForm = UserProps & {
    password: string;
    password_confirmation: string;
};

type RegisterFormProps = {
    user?: UserProps;
    isEdit?: boolean;
    valueButton?: string;
};

export default function RegisterUserForm({ user, isEdit, valueButton }: RegisterFormProps) {
    const router = useRouter();
    const [state, action, pending] = useActionState(createUpdateAdminUser, undefined);
    const [imagePreview, setImagePreview] = useState<string | null>(user?.image ?? null);
    const [imageFile, setImageFile] = useState<File | null>(null);
    const [imageError, setImageError] = useState<string | null>(null);
    const [showPassword, setShowPassword] = useState<boolean>(false);
    const [showPasswordConfirm, setShowPasswordConfirm] = useState<boolean>(false);
    const [data, setData] = useState<RegisterForm>({
        id: user?.id ?? '',
        name: user?.name ?? '',
        email: user?.email ?? '',
        password: '',
        role: user?.role ?? 'USER',
        password_confirmation: '',
        image: user?.image ?? undefined,
    });

    const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
        const { id, value } = e.target;
        setData({ ...data, [id]: value });
    };
    const onImageChange = async (e: ChangeEvent<HTMLInputElement>) => {
        const { file, preview, error } = await handleImageChange(e);
        setImageFile(file);
        setImagePreview(preview);
        setImageError(error);
    };
    const toggleShowPassword = () => setShowPassword(prev => !prev);
    const toggleShowPasswordConfirm = () => setShowPasswordConfirm(prev => !prev);
    const submit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const formData = new FormData(e.currentTarget);
        if (imageFile) formData.append('file', imageFile);
        startTransition(() => action(formData));
    };
    useEffect(() => {
        if (state?.message) {
            const { role } = data;

            if (!isEdit) {
                setData({
                    id: '',
                    name: '',
                    email: '',
                    password: '',
                    role: 'USER',
                    password_confirmation: '',
                    image: undefined,
                });
            }

            if (role === 'USER') {
                router.push('/dashboard/admins/users');
            } else {
                router.push('/dashboard/admins');
            }
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [state]);
    return (
        <form className="w-full max-w-96 flex flex-col gap-6" onSubmit={submit}>
            <div className="grid gap-2">
                <Label htmlFor="file">Foto de perfil</Label>
                <div className="flex flex-col items-center gap-3">
                    <div className="relative w-24 h-24 rounded-full overflow-hidden border border-gray-300">
                        {imagePreview ? (
                            <Image
                                src={imagePreview}
                                alt="Preview"
                                width={512}
                                height={512}
                                className="object-cover w-full h-full"
                            />
                        ) : (
                            <div className="w-full h-full flex items-center justify-center text-sm text-gray-400 bg-gray-50">
                                Sem imagem
                            </div>
                        )}
                    </div>

                    <Label
                        htmlFor="file"
                        className="cursor-pointer px-3 py-1 text-sm border rounded-md hover:bg-gray-50"
                    >
                        Selecionar imagem
                    </Label>
                    <Input
                        id="file"
                        name="file"
                        type="file"
                        tabIndex={1}
                        accept="image/jpeg, image/png, image/webp"
                        onChange={onImageChange}
                        disabled={pending}
                        className="hidden"
                    />
                    {imageError && <InputError message={imageError} />}
                    {state?.errors?.image?.[0] && <InputError message={state.errors.image[0]} />}
                </div>
            </div>

            <div className="grid gap-6">
                {isEdit && (
                    <div className="grid gap-2">
                        <Label htmlFor="id">Cód.</Label>
                        <Input
                            id="id"
                            name="id"
                            type="text"
                            required={isEdit}
                            autoComplete="id"
                            value={data.id}
                            onChange={handleChange}
                            disabled={pending}
                            readOnly
                            placeholder="Cód. do usuário"
                            className="cursor-default"
                        />
                    </div>
                )}

                <div className="grid gap-2">
                    <Label htmlFor="name">Nome</Label>
                    <Input
                        id="name"
                        name="name"
                        type="text"
                        required
                        autoFocus
                        tabIndex={2}
                        autoComplete="name"
                        value={data.name}
                        onChange={handleChange}
                        disabled={pending}
                        placeholder="Nome completo"
                    />
                    {state?.errors?.name?.[0] && <InputError message={state.errors.name[0]} />}
                </div>

                <div className="grid gap-2">
                    <Label htmlFor="email">Endereço de email</Label>
                    <Input
                        id="email"
                        name="email"
                        type="email"
                        required
                        tabIndex={3}
                        autoComplete="email"
                        value={data.email}
                        onChange={handleChange}
                        disabled={pending}
                        placeholder="email@exemplo.com"
                    />
                    {state?.errors?.email?.[0] && <InputError message={state.errors.email[0]} />}
                </div>

                <div className="grid gap-2">
                    <Label htmlFor="password">Senha</Label>
                    <div className="relative">
                        <Input
                            id="password"
                            name="password"
                            type={showPassword ? "text" : "password"}
                            required={!isEdit}
                            tabIndex={4}
                            value={data.password}
                            onChange={handleChange}
                            disabled={pending}
                            placeholder="Senha"
                        />
                        <button
                            type="button"
                            title={showPassword ? "Ocultar senha" : "Mostrar senha"}
                            onClick={toggleShowPassword}
                            className="btn-icon-toggle"
                        >
                            {showPassword ? <Icon iconNode={Eye} /> : <Icon iconNode={EyeClosed} />}
                        </button>
                    </div>
                    {state?.errors?.password?.[0] && <InputError message={state.errors.password[0]} />}
                </div>

                <div className="grid gap-2">
                    <Label htmlFor="password_confirmation">Confirme sua senha</Label>
                    <div className="relative">
                        <Input
                            id="password_confirmation"
                            name="password_confirmation"
                            type={showPasswordConfirm ? "text" : "password"}
                            required={!isEdit}
                            tabIndex={5}
                            value={data.password_confirmation}
                            onChange={handleChange}
                            disabled={pending}
                            placeholder="Confirme sua senha"
                        />
                        <button
                            type="button"
                            title={showPasswordConfirm ? "Ocultar senha" : "Mostrar senha"}
                            onClick={toggleShowPasswordConfirm}
                            className="btn-icon-toggle"
                        >
                            {showPasswordConfirm ? <Icon iconNode={Eye} /> : <Icon iconNode={EyeClosed} />}
                        </button>
                    </div>
                    {state?.errors?.password_confirmation?.[0] && <InputError message={state.errors.password_confirmation[0]} />}
                </div>

                <div className="grid gap-2">
                    <Label htmlFor="role">Tipo de conta</Label>
                    <Select
                        required
                        value={data.role}
                        onValueChange={(value) => setData((prev) => ({ ...prev, role: value }))}
                        disabled={pending}
                    >
                        <SelectTrigger
                            id="role"
                            name="role"
                            title="Selecione o tipo de conta"
                            tabIndex={6}
                        >
                            <SelectValue placeholder="Tipo de conta" />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="USER">
                                Usuário
                            </SelectItem>
                            <SelectItem value="ADMIN">
                                Administrador&#40;a&#41;
                            </SelectItem>
                        </SelectContent>
                    </Select>
                    {state?.errors?.role?.[0] && <InputError message={state.errors.role[0]} />}
                </div>
                <input type="hidden" name="role" value={data.role} />

                <Button type="submit" className="mt-2 w-full" tabIndex={7} disabled={pending} aria-busy={pending}>
                    {pending && <LoaderCircle className="h-4 w-4 animate-spin" />}
                    {valueButton}
                </Button>
            </div>
        </form>
    );
}
