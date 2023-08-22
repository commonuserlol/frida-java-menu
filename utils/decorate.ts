namespace Menu {
    /** @internal */
    export function decorate<T extends object>(
        target: T,
        decorator: (target: T, key: string, descriptor: PropertyDescriptor) => PropertyDescriptor,
        descriptors = globalThis.Object.getOwnPropertyDescriptors(target as any)
    ): T {
        for (const key in descriptors) {
            descriptors[key] = decorator(target, key, descriptors[key]);
        }

        globalThis.Object.defineProperties(target, descriptors);

        return target;
    }
}