export type HandleImageChangeResult = {
    file: File | null;
    preview: string | null;
    error: string | null;
};

export async function handleImageChange(e: React.ChangeEvent<HTMLInputElement>): Promise<HandleImageChangeResult> {
    const file = e.target.files?.[0];
    if (!file) return { file: null, preview: null, error: null };

    if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
        return { file: null, preview: null, error: 'Apenas imagens JPEG, PNG ou WebP são permitidas.' };
    }

    if (file.size > 512 * 1024) {
        return { file: null, preview: null, error: 'A imagem não pode ultrapassar 512 KB.' };
    }

    try {
        const imageBitmap = await createImageBitmap(file);
        const { width, height } = imageBitmap;

        if (width > 512 || height > 512) {
            return {
                file: null,
                preview: null,
                error: `A imagem não pode ter dimensões maiores que 512x512 pixels (atual: ${width}x${height}).`,
            };
        }
    } catch {
        return { file: null, preview: null, error: 'Falha ao ler as dimensões da imagem.' };
    }

    return {
        file,
        preview: URL.createObjectURL(file),
        error: null,
    };
}