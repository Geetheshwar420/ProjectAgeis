/**
 * FileService.ts
 * Handles file uploads and integration with the backend storage endpoint.
 */

import api from './api';

export interface UploadResponse {
    url: string;
    filename: string;
    content_type: string;
    size: number;
}

export class FileService {
    /**
     * Upload a file to the backend
     * @param file The file object from a file input
     * @param onProgress Callback for upload progress
     */
    public static async uploadFile(
        file: File,
        onProgress?: (progress: number) => void
    ): Promise<UploadResponse> {
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await api.post('/upload', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                },
                onUploadProgress: (progressEvent) => {
                    if (onProgress && progressEvent.total) {
                        const percentCompleted = Math.round(
                            (progressEvent.loaded * 100) / progressEvent.total
                        );
                        onProgress(percentCompleted);
                    }
                }
            });

            return response.data;
        } catch (error) {
            console.error('File upload failed:', error);
            throw new Error('Failed to upload file. Please try again.');
        }
    }

    /**
     * Helper to determine if a file is an image
     */
    public static isImage(filename: string): boolean {
        const ext = filename.split('.').pop()?.toLowerCase();
        return ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'].includes(ext || '');
    }
}
