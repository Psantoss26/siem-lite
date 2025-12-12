from __future__ import annotations
import io
import os
import time
from typing import Iterator, List, Dict, Optional

class FileCollector:
    """
    Lector de ficheros tipo tail.
    - Soporta rotación (detecta cambio de inode y reabre).
    - start_at_end=True: comienza al final del fichero (modo tail).
    - follow=True: si no hay nuevas líneas, espera y continúa.
    - follow=False: si no hay nuevas líneas, termina.
    """

    def __init__(
        self,
        paths: List[str],
        poll_interval: float = 0.5,
        encoding: str = "utf-8",
        start_at_end: bool = True,
        follow: bool = False,
        idle_exit_sec: Optional[float] = None,  # si no hay datos durante N s y follow=True → salir
        max_events: Optional[int] = None,       # límite de líneas emitidas
    ) -> None:
        self.paths = paths
        self.poll_interval = poll_interval
        self.encoding = encoding
        self.start_at_end = start_at_end
        self.follow = follow
        self.idle_exit_sec = idle_exit_sec
        self.max_events = max_events

        self._handles: Dict[str, io.TextIOWrapper] = {}
        self._stats: Dict[str, tuple] = {}

    def _open(self, path: str) -> io.TextIOWrapper:
        f = open(path, "r", encoding=self.encoding, errors="replace")
        if self.start_at_end:
            f.seek(0, os.SEEK_END)
        st = os.fstat(f.fileno())
        self._handles[path] = f
        self._stats[path] = (st.st_dev, st.st_ino)
        return f

    def _reopen_if_rotated(self, path: str) -> Optional[io.TextIOWrapper]:
        f = self._handles.get(path)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            if f and not f.closed:
                f.close()
            self._handles.pop(path, None)
            self._stats.pop(path, None)
            return None

        prev = self._stats.get(path)
        current = (st.st_dev, st.st_ino)
        if f is None or prev != current:
            if f and not f.closed:
                f.close()
            return self._open(path)
        return f

    def lines(self) -> Iterator[dict]:
        # Abrimos los ficheros iniciales
        for p in self.paths:
            try:
                self._open(p)
            except FileNotFoundError:
                pass

        emitted_total = 0
        idle_accum = 0.0

        while True:
            emitted_this_cycle = False
            cycle_start = time.time()

            for path in list(self.paths):
                f = self._reopen_if_rotated(path)
                if not f:
                    continue
                while True:
                    pos = f.tell()
                    line = f.readline()
                    if not line:
                        f.seek(pos)
                        break
                    emitted_this_cycle = True
                    emitted_total += 1
                    yield {"path": path, "line": line.rstrip("\n")}
                    if self.max_events is not None and emitted_total >= self.max_events:
                        return

            if emitted_this_cycle:
                idle_accum = 0.0
            else:
                # No hubo líneas nuevas
                if not self.follow:
                    # Modo no-follow: terminamos en cuanto no haya más datos
                    return

                # Modo follow: esperamos poll_interval y acumulamos inactividad
                elapsed = time.time() - cycle_start
                sleep_for = max(0.0, self.poll_interval - elapsed)
                if sleep_for > 0:
                    time.sleep(sleep_for)
                idle_accum += (time.time() - cycle_start)

                if self.idle_exit_sec is not None and idle_accum >= self.idle_exit_sec:
                    # En follow pero inactivo demasiado tiempo → salir
                    return
