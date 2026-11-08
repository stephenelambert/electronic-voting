import { useEffect, useState } from "react";

// useDebouncedValue returns value once it has stopped changing for delay_ms, so typing in a search
// box doesn't send a request for every keystroke
export function useDebouncedValue<T>(value : T, delay_ms : number) : T {
    const [debounced, setDebounced] = useState<T>(value);

    useEffect(() => {
        const timeout = setTimeout(() => setDebounced(value), delay_ms);
        return () => clearTimeout(timeout);
    }, [value, delay_ms]);

    return debounced;
}
