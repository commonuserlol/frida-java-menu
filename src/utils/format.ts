namespace Menu {
    /** Formats text like `format("hi {}", "commonuserlol")` */
    export function format(str: string, ...obj: any): string {
        return str.replace(/\{\s*([^}\s]+)\s*\}/g, function(m, p1, offset, string) {
            return obj[p1]
        });
    }
}