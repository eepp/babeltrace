define bt-resolve-show-type-stack
    set $type_stack_at = (int) (type_stack_size($arg0) - 1)

    while ($type_stack_at >= 0)
        set $type_stack_frame = type_stack_at($arg0, $type_stack_at)
        printf "%3d    %10p    %3d\n", $type_stack_at, \
            $type_stack_frame->type, $type_stack_frame->index
        set $type_stack_at = $type_stack_at - 1
    end
end

document bt-resolve-show-type-stack
Print the elements of a Babeltrace resolving type stack
end
