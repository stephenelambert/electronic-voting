import React from "react";
import { Badge } from "react-bootstrap";
import { electionStatus, ElectionStatus } from "@/services/electionservice";

const LABELS : Record<ElectionStatus, string> = {
    upcoming: "Upcoming",
    open: "Open",
    closed: "Closed",
}

const VARIANTS : Record<ElectionStatus, string> = {
    upcoming: "info",
    open: "success",
    closed: "secondary",
}

interface ElectionStatusBadgeProps {
    time_open: number;
    time_close: number;
}

// ElectionStatusBadge shows whether an election is upcoming, open, or closed, going by the
// browser's clock
export default function ElectionStatusBadge({ time_open, time_close } : ElectionStatusBadgeProps) : React.JSX.Element {
    const status : ElectionStatus = electionStatus({ time_open, time_close }, Date.now() / 1000)

    return <Badge bg={VARIANTS[status]}>{LABELS[status]}</Badge>
}
