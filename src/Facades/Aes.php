<?php
/**
 * xxx
 * @link   	   
 * @author  oyzm <o.yyyy@qq.com>
 */
namespace Oyzmer\phpAes\Facade;


use Illuminate\Support\Facades\Facade;

class Aes extends Facade
{
    
    protected static function getFacadeAccessor(){
        
        return 'Aes';
    }
    
}